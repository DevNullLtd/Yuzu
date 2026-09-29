asset_tags_plugin_lib = shared_library(
  'asset_tags',
  files('src/asset_tags_plugin.cpp'),
  name_prefix: '',
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep, nlohmann_dep, spdlog_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
