# shares -- what this host serves over SMB/NFS (read-only, configured shares).
# Multi-TU shape follows agents/plugins/mgmt_posture/meson.build: one portable plugin TU
# plus three per-OS leg TUs, each #ifdef-gated internally for its own target so all four are
# listed unconditionally. The Linux leg reads config files in-process; the macOS leg runs
# one argv through the bounded runner (yuzu_agent_core_dep) and reads /etc/exports; the
# Windows leg is a PLANNED placeholder that reads nothing. nlohmann parses `sharing` JSON.
shares_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, nlohmann_dep]

# Assigned (not anonymous) so tests/meson.build's link_depends can name this build output,
# matching mgmt_posture_plugin_lib.
shares_plugin_lib = shared_library(
  'shares',
  files(
    'src/shares_plugin.cpp',
    'src/shares_linux.cpp',
    'src/shares_macos.cpp',
    'src/shares_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: shares_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
