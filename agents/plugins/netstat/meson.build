netstat_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

if host_machine.system() == 'windows'
  netstat_deps += cxx.find_library('iphlpapi')
  netstat_deps += cxx.find_library('ws2_32')
endif

# Captured (not just built) so tests/meson.build can order it ahead of
# agent_test_exe via link_depends -- test_netstat_attribution.cpp loads this
# plugin by path (same shape as os_info_plugin_lib / users_plugin_lib).
netstat_plugin_lib = shared_library(
  'netstat',
  files('src/netstat_plugin.cpp'),
  name_prefix: '',
  # macos_socket_walk.hpp (#3403 dedupe, darwin) + win_str.hpp (#1681, windows attribution)
  include_directories: include_directories('../../shared'),
  dependencies: netstat_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
