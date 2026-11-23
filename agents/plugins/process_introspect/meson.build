# process_introspect -- read-only introspection of one process (Linux; macOS and Windows planned).
# Two TUs: the portable plugin TU and the Linux shell (empty off Linux, so listed
# unconditionally). yuzu_agent_core_dep supplies the host context symbols the SDK wrapper
# links against (yuzu_ctx_write_output and friends).
process_introspect_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

# Assigned (not anonymous) so tests/meson.build's link_depends can name this build output.
process_introspect_plugin_lib = shared_library(
  'process_introspect',
  files(
    'src/process_introspect_plugin.cpp',
    'src/process_introspect_linux.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: process_introspect_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
