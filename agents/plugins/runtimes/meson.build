# runtimes -- installed .NET / JVM runtime inventory (read-only, zero subprocess).
# Multi-TU shape follows agents/plugins/peripherals/meson.build: one portable
# plugin TU plus three per-OS leg TUs, each #if-gated internally for its own
# target so all four are listed unconditionally. No platform frameworks or
# libraries: the legs read directory names and metadata files only.
runtimes_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]

# Assigned (not anonymous) so tests/meson.build's link_depends can name this
# build output, matching peripherals_plugin_lib / disk_actions_plugin_lib.
runtimes_plugin_lib = shared_library(
  'runtimes',
  files(
    'src/runtimes_plugin.cpp',
    'src/runtimes_linux.cpp',
    'src/runtimes_macos.cpp',
    'src/runtimes_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: runtimes_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
