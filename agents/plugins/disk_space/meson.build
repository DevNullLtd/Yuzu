# Captured so tests/meson.build can order it ahead of agent_test_exe via link_depends.
disk_space_plugin_lib = shared_library(
  'disk_space',
  files('src/disk_space_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681, _WIN32-gated)
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
