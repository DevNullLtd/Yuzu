#pragma once

/// @file all_fragments.hpp
/// The 28 capability fragments, spelled ONCE. A macro because
/// CommandCapabilityRegistry and enablement::build_unit_overlay both take a
/// brace-enclosed initializer_list, which a function cannot forward. The server's
/// dispatch registry (server.cpp capability_registry_), the boot-time unit overlay
/// (enablement_store construction) and the units test all expand it, so the
/// registry, the overlay and the test can never drift apart on which fragments
/// exist. A new fragment is added here and nowhere else.
///
/// The order is the registry's (core first). Order is irrelevant to the overlay,
/// which sorts by unit name.

#include "core_dispatch_capabilities.hpp"
#include "plugin_action_catalogue_a.hpp"
#include "plugin_action_catalogue_app_control.hpp"
#include "plugin_action_catalogue_app_usage.hpp"
#include "plugin_action_catalogue_autoruns.hpp"
#include "plugin_action_catalogue_b.hpp"
#include "plugin_action_catalogue_browser_inventory.hpp"
#include "plugin_action_catalogue_browser_policy.hpp"
#include "plugin_action_catalogue_c.hpp"
#include "plugin_action_catalogue_content_dist.hpp"
#include "plugin_action_catalogue_d.hpp"
#include "plugin_action_catalogue_disk_actions.hpp"
#include "plugin_action_catalogue_execution_artifacts.hpp"
#include "plugin_action_catalogue_filesystem_posture.hpp"
#include "plugin_action_catalogue_firmware_posture.hpp"
#include "plugin_action_catalogue_local_security_policy.hpp"
#include "plugin_action_catalogue_mgmt_posture.hpp"
#include "plugin_action_catalogue_peripherals.hpp"
#include "plugin_action_catalogue_pkg_inventory.hpp"
#include "plugin_action_catalogue_platform_security.hpp"
#include "plugin_action_catalogue_power_health.hpp"
#include "plugin_action_catalogue_printing.hpp"
#include "plugin_action_catalogue_privacy_permissions.hpp"
#include "plugin_action_catalogue_runtimes.hpp"
#include "plugin_action_catalogue_shares.hpp"
#include "plugin_action_catalogue_system_hardening.hpp"
#include "plugin_action_catalogue_update_source_trust.hpp"
#include "plugin_action_catalogue_windows_optional_features.hpp"

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
