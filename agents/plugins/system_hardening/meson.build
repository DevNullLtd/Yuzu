# system_hardening -- exploit-mitigation / kernel-hardening posture (read-only).
# Multi-TU shape follows agents/plugins/peripherals/meson.build: one portable
# plugin TU plus three per-OS leg TUs, each #ifdef-gated internally for its own
# target so all four are listed unconditionally. /proc/sys is plain POSIX I/O
# and sysctlbyname is libc, so only the Windows leg needs an import library.
system_hardening_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]

if host_machine.system() == 'windows'
  # advapi32: RegQueryValueExW for the Session Manager\kernel mitigation values.
  # GetProcessMitigationPolicy lives in kernel32, already an MSVC default lib.
  system_hardening_deps += [
    cxx.find_library('advapi32'),
  ]
endif

# Assigned (not anonymous) so tests/meson.build's link_depends can name this
# build output, matching peripherals_plugin_lib / filesystem_posture_plugin_lib.
system_hardening_plugin_lib = shared_library(
  'system_hardening',
  files(
    'src/system_hardening_plugin.cpp',
    'src/system_hardening_linux.cpp',
    'src/system_hardening_macos.cpp',
    'src/system_hardening_win.cpp',
  ),
  name_prefix: '',
  # ../../shared: constraint_accumulator.hpp (+ win_reg_handle.hpp/win_str.hpp
  # for the Windows leg).
  include_directories: include_directories('../../shared'),
  dependencies: system_hardening_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
