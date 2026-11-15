# middleware -- installed middleware inventory from installer metadata (read-only, zero subprocess).
# Multi-TU shape follows agents/plugins/runtimes/meson.build: one portable plugin TU plus
# three per-OS leg TUs, each #if-gated internally for its own target so all four are listed
# unconditionally. No platform frameworks or libraries: the legs read installer metadata files
# only.
middleware_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]

# Assigned (not anonymous) so tests/meson.build's link_depends can name this
# build output, matching runtimes_plugin_lib / peripherals_plugin_lib.
middleware_plugin_lib = shared_library(
  'middleware',
  files(
    'src/middleware_plugin.cpp',
    'src/middleware_linux.cpp',
    'src/middleware_macos.cpp',
    'src/middleware_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: middleware_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
