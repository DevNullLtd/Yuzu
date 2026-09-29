shared_library(
  'services',
  files('src/services_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681)
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
