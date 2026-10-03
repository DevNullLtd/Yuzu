# local_security_policy -- password/lockout/audit policy posture and sudoers content
# (read-only). Portable TU plus per-OS leg TUs (Linux, macOS, Windows), each #ifdef-gated
# internally, listed unconditionally (agents/plugins/peripherals/meson.build's shape).
local_security_policy_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]

if host_machine.system() == 'windows'
  # advapi32: the scratch-dir owner check (OpenProcessToken/GetTokenInformation).
  local_security_policy_deps += [cxx.find_library('advapi32')]
elif host_machine.system() == 'darwin'
  # CoreFoundation: CFPropertyListCreateWithData (pwpolicy plist).
  local_security_policy_deps += dependency('appleframeworks', modules: ['CoreFoundation'],
                                           include_type: 'system')
endif

# Assigned so tests/meson.build's link_depends can order this build ahead of
# test_local_security_policy_local_dispatcher.cpp, which loads the real library by path.
local_security_policy_plugin_lib = shared_library(
  'local_security_policy',
  files(
    'src/local_security_policy_plugin.cpp',
    'src/local_security_policy_linux.cpp',
    'src/local_security_policy_macos.cpp',
    'src/local_security_policy_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: local_security_policy_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
