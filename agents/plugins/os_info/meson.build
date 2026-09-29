# Captured (not just built) so tests/meson.build can order it ahead of
# agent_test_exe via link_depends -- test_wave3_pr31_macos_actions.cpp loads
# this plugin by path (same shape as users_plugin_lib).
os_info_plugin_lib = shared_library(
  'os_info',
  files('src/os_info_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681)
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
