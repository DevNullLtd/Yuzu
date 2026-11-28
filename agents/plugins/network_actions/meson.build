network_actions_plugin_lib = shared_library(
  'network_actions',
  files('src/network_actions_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # sudo_argv.hpp, host_arg.hpp
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
# deploy_dlls (root meson.build) waits for every library in this list (#8926).
yuzu_plugin_libs += network_actions_plugin_lib
