diagnostics_plugin_lib = shared_library(
  'diagnostics',
  files('src/diagnostics_plugin.cpp'),
  name_prefix: '',
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
# deploy_dlls (root meson.build) waits for every library in this list (#8926).
yuzu_plugin_libs += diagnostics_plugin_lib
