app_usage_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, sqlite3_dep]
app_usage_sources = files('src/app_usage_plugin.cpp')

# Assigned to a variable (mirrors power_health_plugin_lib in
# agents/plugins/power_health/meson.build) so tests/meson.build's
# link_depends can order this build ahead of
# test_app_usage_local_dispatcher.cpp, which loads the real
# app_usage.dylib/.so/.dll by path via yuzu::agent::PluginHandle::load.
app_usage_plugin_lib = shared_library(
  'app_usage',
  app_usage_sources,
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: app_usage_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
