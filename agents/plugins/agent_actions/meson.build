# Named so tests/meson.build can `depends:` on the built plugin object for the #4666
# PR-2 macOS multi-image fixture (MI-3, a real-plugin log-level dispatch measurement).
agent_actions_plugin_lib = shared_library(
  'agent_actions',
  files('src/agent_actions_plugin.cpp'),
  name_prefix: '',
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
