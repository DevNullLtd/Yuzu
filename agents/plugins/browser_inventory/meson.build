# browser_inventory — Chromium-family browser/profile inventory
# (Forensics securable, default-off). Multi-TU shape follows
# agents/plugins/peripherals/meson.build: one portable plugin TU plus three
# per-OS leg TUs, each #ifdef-gated internally for its own target so all
# four are listed unconditionally. No OS-framework dependency this wave --
# the macOS/Windows legs are FINAL placeholders; the Linux leg is a real
# read (pure filesystem + JSON, no IOKit/SetupAPI).
browser_inventory_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, nlohmann_dep]

# Assigned (not anonymous) so tests/meson.build's link_depends can name this
# build output, matching peripherals_plugin_lib / asset_tags's convention.
browser_inventory_plugin_lib = shared_library(
  'browser_inventory',
  files(
    'src/browser_inventory_plugin.cpp',
    'src/browser_inventory_linux.cpp',
    'src/browser_inventory_macos.cpp',
    'src/browser_inventory_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: browser_inventory_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
