script_exec_plugin_lib = shared_library(
  'script_exec',
  files('src/script_exec_plugin.cpp'),
  name_prefix: '',
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep],
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681, _WIN32-gated; BR4-004)
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
