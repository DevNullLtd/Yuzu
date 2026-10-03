# browser_policy — enterprise-managed Chrome/Chromium/Edge policy inventory
# (read-only). Multi-TU shape follows agents/plugins/peripherals/meson.build:
# one portable plugin TU plus three per-OS leg TUs, each #if-gated internally
# for its own target so all four are listed unconditionally.
browser_policy_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, nlohmann_dep]

# Assigned (not anonymous) so tests/meson.build's link_depends can name this
# build output, matching peripherals_plugin_lib / disk_actions_plugin_lib.
browser_policy_plugin_lib = shared_library(
  'browser_policy',
  files(
    'src/browser_policy_plugin.cpp',
    'src/browser_policy_linux.cpp',
    'src/browser_policy_macos.cpp',
    'src/browser_policy_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: browser_policy_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
