# process_introspect -- read-only introspection of one process (Linux and macOS; Windows planned).
# Three TUs: the portable plugin TU and the Linux and macOS shells (each empty off its own OS,
# so listed unconditionally). yuzu_agent_core_dep supplies the host context symbols the SDK wrapper
# links against (yuzu_ctx_write_output and friends).
process_introspect_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

# Assigned (not anonymous) so tests/meson.build's link_depends can name this build output.
process_introspect_plugin_lib = shared_library(
  'process_introspect',
  files(
    'src/process_introspect_plugin.cpp',
    'src/process_introspect_linux.cpp',
    'src/process_introspect_macos.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: process_introspect_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
# deploy_dlls (root meson.build) waits for every library in this list (#8926).
yuzu_plugin_libs += process_introspect_plugin_lib
