# remote_access_audit -- who can log in over SSH (read-only, configured access).
# Multi-TU shape follows agents/plugins/shares/meson.build: one portable plugin TU plus three
# per-OS leg TUs, each #ifdef-gated internally for its own target so all four are listed
# unconditionally. The Linux and macOS legs read sshd_config and authorized_keys in-process
# and run one bounded argv (systemctl / launchctl); the Windows leg is a PLANNED placeholder
# that reads nothing. yuzu_agent_core_dep supplies the host context symbols the SDK wrapper
# links against (yuzu_ctx_write_output and friends) and the bounded subprocess runner.
remote_access_audit_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

# Assigned (not anonymous) so tests/meson.build's link_depends can name this build output,
# matching shares_plugin_lib.
remote_access_audit_plugin_lib = shared_library(
  'remote_access_audit',
  files(
    'src/remote_access_audit_plugin.cpp',
    'src/remote_access_audit_linux.cpp',
    'src/remote_access_audit_macos.cpp',
    'src/remote_access_audit_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: remote_access_audit_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
