ioc_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

if host_machine.system() == 'windows'
  ioc_deps += cxx.find_library('iphlpapi')
  ioc_deps += cxx.find_library('ws2_32')
endif

# Captured (not just built) so tests/meson.build can order it ahead of
# agent_test_exe via link_depends -- test_wave3_pr31_macos_actions.cpp loads
# this plugin by path (same shape as users_plugin_lib).
ioc_plugin_lib = shared_library(
  'ioc',
  files('src/ioc_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681, _WIN32-gated);
                                                                # macos_socket_walk.hpp (Wave 3 PR3.1)
  dependencies: ioc_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
