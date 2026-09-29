device_identity_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]
device_identity_args = []

if host_machine.system() == 'windows'
  device_identity_deps += cxx.find_library('netapi32')
  device_identity_deps += cxx.find_library('secur32')
elif host_machine.system() == 'linux'
  # Wave 3 (#2380/ADR-3002 promotion): do_domain's AD-join check tries
  # sssd's InfoPipe (org.freedesktop.sssd.infopipe ListDomains) over sd-bus
  # first (rung 1, zero processes) instead of unconditionally shelling out to
  # `realm list`. Reuses the SAME systemd_guard tri-state feature option
  # agent-core already defines (agents/core/meson.build) — never a second
  # option — and mirrors its enabled/auto/disabled + YUZU_HAVE_LIBSYSTEMD
  # compile-gate shape so an sd-bus-less build still compiles (falls through
  # to the bounded `realm list` runner call -- do_ou's existing, already-
  # unprivileged call site to the same binary -- then to the sssd.conf
  # ifstream read at runtime; see BR-011 in the fixup commit for why `realm
  # list` had to come back as an intermediate fallback rather than going
  # straight to the file read).
  libsystemd_dep = dependency('libsystemd', required: get_option('systemd_guard'),
                              include_type: 'system')
  if libsystemd_dep.found()
    device_identity_deps += libsystemd_dep
    device_identity_args += '-DYUZU_HAVE_LIBSYSTEMD'
  else
    message('libsystemd not used (systemd_guard != enabled, and not found) — device_identity '
          + 'do_domain falls back to the sssd.conf read unconditionally')
  endif
endif

# Assigned to a variable (mirrors users_plugin_lib in
# agents/plugins/users/meson.build) so tests/meson.build's link_depends can
# order this build ahead of test_hardware_device_identity_posix_actions.cpp,
# which loads the real device_identity.dylib/.so by path via
# yuzu::agent::PluginHandle::load.
device_identity_plugin_lib = shared_library(
  'device_identity',
  files('src/device_identity_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681, _WIN32-gated)
  dependencies: device_identity_deps,
  cpp_args: device_identity_args,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
