power_health_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
power_health_sources = files('src/power_health_plugin.cpp')
power_health_objcpp_args = []

if host_machine.system() == 'windows'
  power_health_deps += [
    cxx.find_library('powrprof'),
    cxx.find_library('pdh'),
  ]
elif host_machine.system() == 'darwin'
  # Second Objective-C++ (.mm) plugin TU in the tree, following wifi's
  # template (docs/native-objcpp-conventions.md) -- Foundation
  # (NSProcessInfo) and IOKit (IOPSCopyPowerSourcesInfo/IOPSCopyPower-
  # SourcesList, IOPMGetThermalWarningLevel) are both public frameworks in
  # the base macOS SDK, present with the Command Line Tools SDK, so
  # required: true is correct here (a configure-time failure to find either
  # is a real toolchain problem). add_languages('objcpp', ...) and
  # apple_objcpp_args are declared once at the top-level meson.build's
  # Darwin-frameworks site -- never repeated here.
  power_health_sources += files('src/power_health_macos.mm')
  power_health_deps += dependency('appleframeworks', modules: ['Foundation', 'IOKit'],
                                  include_type: 'system')
  power_health_objcpp_args += apple_objcpp_args
endif

# Assigned to a variable (mirrors wifi_plugin_lib in
# agents/plugins/wifi/meson.build) so tests/meson.build's link_depends can
# order this build ahead of test_power_health_local_dispatcher.cpp, which
# loads the real power_health.dylib/.so/.dll by path via
# yuzu::agent::PluginHandle::load.
power_health_plugin_lib = shared_library(
  'power_health',
  power_health_sources,
  name_prefix: '',
  # ../../shared: bounded_wait.hpp (all platforms) and win_str.hpp (_WIN32-gated).
  include_directories: include_directories('../../shared'),
  dependencies: power_health_deps,
  objcpp_args: power_health_objcpp_args,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
