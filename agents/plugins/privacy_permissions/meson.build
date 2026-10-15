# privacy_permissions -- per-app sensitive-permission grant visibility (read-only). One
# portable plugin TU plus three self-gated per-OS leg TUs (platform_security/peripherals
# shape). Windows needs no import library beyond advapi32 (registry only, no spawn/WMI).
# macOS links the same vcpkg sqlite3_dep app_usage/meson.build already uses (in-process
# TCC.db read, never a `sqlite3` CLI shellout). Linux links libsystemd the same
# systemd_guard-gated way firmware_posture/meson.build and firewall/meson.build do, for a
# SESSION-bus (not system-bus) xdg-desktop-portal call.
privacy_permissions_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]
privacy_permissions_cpp_args = []

if host_machine.system() == 'windows'
  privacy_permissions_deps += [cxx.find_library('advapi32')]
elif host_machine.system() == 'darwin'
  privacy_permissions_deps += [sqlite3_dep]
elif host_machine.system() == 'linux'
  libsystemd_dep = dependency('libsystemd', required: get_option('systemd_guard'),
                              include_type: 'system')
  if libsystemd_dep.found()
    privacy_permissions_deps += libsystemd_dep
    privacy_permissions_cpp_args += '-DYUZU_HAVE_LIBSYSTEMD'
  else
    message('PRIVACY_PERMISSIONS: libsystemd not used (systemd_guard != enabled, and not '
          + 'found) -- the portal read compiles as unreachable and reports portal:not_built')
  endif
endif

# Assigned (not anonymous) so tests/meson.build's link_depends can name this build output.
privacy_permissions_plugin_lib = shared_library(
  'privacy_permissions',
  files(
    'src/privacy_permissions_plugin.cpp',
    'src/privacy_permissions_linux.cpp',
    'src/privacy_permissions_macos.cpp',
    'src/privacy_permissions_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # constraint_accumulator.hpp, win_*
  cpp_args: privacy_permissions_cpp_args,
  dependencies: privacy_permissions_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
