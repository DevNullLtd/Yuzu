# virtualization -- is this device a VM, which hypervisor, is the agent in a container
# (read-only facts). Multi-TU shape follows agents/plugins/mgmt_posture/meson.build: one
# portable plugin TU plus three per-OS leg TUs, each #ifdef-gated internally for its own
# target so all four are listed unconditionally. No subprocess: CPUID, sysctl, sysfs/procfs
# reads and the Windows RSMB firmware table are all in-process.
virtualization_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep, nlohmann_dep]

# runtime_posture (Linux): an HTTP client over the operator's unix socket (printing/meson.build
# precedent). Windows and macOS legs answer one unsupported row and need no client.
if host_machine.system() == 'linux'
  virtualization_deps += httplib_dep
endif

# win_profiles.hpp (the `wsl` action's with_user_hive ladder) calls Reg*W, RegLoadKeyW and
# AdjustTokenPrivileges, which live in advapi32 (installed_apps/meson.build precedent).
if host_machine.system() == 'windows'
  virtualization_deps += meson.get_compiler('cpp').find_library('advapi32')
endif

# Assigned (not anonymous) so tests/meson.build's link_depends can name this build output,
# matching mgmt_posture_plugin_lib.
virtualization_plugin_lib = shared_library(
  'virtualization',
  files(
    'src/virtualization_plugin.cpp',
    'src/virtualization_linux.cpp',
    'src/virtualization_macos.cpp',
    'src/virtualization_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: virtualization_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
