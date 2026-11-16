hardware_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, nlohmann_dep, spdlog_dep]

if host_machine.system() == 'windows'
  hardware_deps += cxx.find_library('wbemuuid')
  hardware_deps += cxx.find_library('ole32')
  hardware_deps += cxx.find_library('oleaut32')
  # RegOpenKeyExW / RegQueryValueExW (the machine_id leg's MachineGuid read) are advapi32; the same
  # lookup app_control/meson.build uses.
  hardware_deps += cxx.find_library('advapi32')
elif host_machine.system() == 'darwin'
  # Wave 3 (#2380/ADR-3002 promotion): the "system" action reads the IOKit
  # IOPlatformExpertDevice registry entry natively (kIOPlatformSerialNumberKey
  # / kIOPlatformUUIDKey) instead of shelling out to `ioreg`. Same dependency shape as
  # tests/meson.build's agent_test_native_deps (PLAN-08). As of C0 (dex_macos_perf.cpp)
  # agent-core DOES link IOKit/CoreFoundation on darwin (its own hard appleframeworks
  # dependency, agents/core/meson.build) — but a shared_library's own `dependencies:` are
  # NOT propagated to a `link_with:` consumer by Meson (unlike
  # `declare_dependency(dependencies: [...])`, which yuzu_agent_core_dep does not use for
  # this), so this plugin must still carry its own copy of the frameworks it directly
  # includes headers from.
  hardware_deps += dependency('appleframeworks', modules: ['IOKit', 'CoreFoundation'],
                               include_type: 'system')
endif

# Assigned to a variable (mirrors users_plugin_lib in
# agents/plugins/users/meson.build) so tests/meson.build's link_depends can
# order this build ahead of test_hardware_device_identity_posix_actions.cpp,
# which loads the real hardware.dylib/.so by path via
# yuzu::agent::PluginHandle::load.
hardware_plugin_lib = shared_library(
  'hardware',
  # hardware_estate_win.cpp is #ifdef _WIN32 inside, so it is listed unconditionally (the shape
  # firmware_posture/meson.build uses for its per-OS leg TUs).
  files('src/hardware_plugin.cpp', 'src/hardware_estate_win.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # wmi_bounded.hpp (#3404, _WIN32-gated), planned_leg.hpp, win_rsmb.hpp, hmac_sha256.hpp
  dependencies: hardware_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
