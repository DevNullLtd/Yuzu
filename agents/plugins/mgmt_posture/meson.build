# mgmt_posture -- which management plane controls the device (read-only facts).
# Multi-TU shape follows agents/plugins/update_source_trust/meson.build: one portable
# plugin TU plus three per-OS leg TUs, each #ifdef-gated internally for its own
# target so all four are listed unconditionally. The Linux leg reads config files
# in-process; the macOS leg runs one argv through the bounded runner (yuzu_agent_core_dep);
# the Windows leg is a PLANNED placeholder that reads nothing.
mgmt_posture_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]

# Assigned (not anonymous) so tests/meson.build's link_depends can name this
# build output, matching update_source_trust_plugin_lib.
mgmt_posture_plugin_lib = shared_library(
  'mgmt_posture',
  files(
    'src/mgmt_posture_plugin.cpp',
    'src/mgmt_posture_linux.cpp',
    'src/mgmt_posture_macos.cpp',
    'src/mgmt_posture_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: mgmt_posture_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
