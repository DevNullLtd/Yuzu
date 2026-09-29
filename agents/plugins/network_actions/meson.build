shared_library(
  'network_actions',
  files('src/network_actions_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # sudo_argv.hpp, host_arg.hpp
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
