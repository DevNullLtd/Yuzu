# platform_security -- Secure Boot / code-integrity posture (read-only). One
# portable plugin TU plus three self-gated per-OS leg TUs (peripherals shape).
# Only the Windows leg needs an import library (advapi32: RegQueryValueExW).
# The rig probe session tried WldpGetLockdownPolicy (wldp.dll) and decided
# against shipping it (see the platform_security_win.cpp banner) -- no
# LoadLibrary/GetProcAddress of wldp.dll exists in the shipped code.
platform_security_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]

if host_machine.system() == 'windows'
  platform_security_deps += [
    cxx.find_library('advapi32'),
  ]
endif

# Assigned so tests/meson.build's link_depends can name this build output.
platform_security_plugin_lib = shared_library(
  'platform_security',
  files(
    'src/platform_security_plugin.cpp',
    'src/platform_security_linux.cpp',
    'src/platform_security_macos.cpp',
    'src/platform_security_win.cpp',
  ),
  name_prefix: '',
  # ../../shared: constraint_accumulator.hpp (+ win_* helpers for the Windows leg).
  include_directories: include_directories('../../shared'),
  dependencies: platform_security_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
