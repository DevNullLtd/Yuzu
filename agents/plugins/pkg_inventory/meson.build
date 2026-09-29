# pkg_inventory — machine-scope package-manager inventory (read-only, no spawn).
# Multi-TU shape follows agents/plugins/peripherals/meson.build: one portable
# plugin TU plus three per-OS leg TUs, each #if-gated internally for its own
# target so all four are listed unconditionally. No libxml2 (the Windows
# Chocolatey nuspec leg is a follow-up PR) and no OS framework: every read is
# open/openat/readdir through agents/shared/posix_dir_walk.hpp.
pkg_inventory_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]

# Assigned (not anonymous) so tests/meson.build's link_depends can name this
# build output, matching peripherals_plugin_lib.
pkg_inventory_plugin_lib = shared_library(
  'pkg_inventory',
  files(
    'src/pkg_inventory_plugin.cpp',
    'src/pkg_inventory_linux.cpp',
    'src/pkg_inventory_macos.cpp',
    'src/pkg_inventory_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: pkg_inventory_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
