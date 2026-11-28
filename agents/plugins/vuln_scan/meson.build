vuln_scan_plugin_lib = shared_library(
  'vuln_scan',
  files('src/vuln_scan_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681)
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
# deploy_dlls (root meson.build) waits for every library in this list (#8926).
yuzu_plugin_libs += vuln_scan_plugin_lib
