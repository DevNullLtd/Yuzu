# firmware_posture -- BIOS/UEFI firmware vendor, version and update-pending posture (read-only).
# Shape follows peripherals/meson.build: a portable plugin TU plus three per-OS leg TUs, each
# #ifdef-gated internally for its own target, so all four are listed unconditionally.
firmware_posture_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]
firmware_posture_cpp_args = []

if host_machine.system() == 'darwin'
  # IOKit for IORegistryEntryFromPath/IORegistryEntryCreateCFProperty on the IODeviceTree
  # plane; CoreFoundation for the CFData those return. agent-core's IOKit link does
  # NOT propagate to a shared_library consumer, so it is named here exactly as
  # hardware/meson.build:18-19 does.
  firmware_posture_deps += dependency('appleframeworks', modules: ['IOKit', 'CoreFoundation'],
                                      include_type: 'system')
elif host_machine.system() == 'windows'
  # Win32_BIOS goes through agents/shared/wmi_bounded.hpp (COM/WMI interface IDs): the same
  # three libraries bitlocker/meson.build:14-16 links. GetSystemFirmwareTable is kernel32.
  firmware_posture_deps += [cxx.find_library('wbemuuid'), cxx.find_library('ole32'),
                            cxx.find_library('oleaut32')]
elif host_machine.system() == 'linux'
  # sd-bus to org.freedesktop.fwupd: a system dependency (never a vcpkg.json entry), gated by
  # agent-core's existing systemd_guard feature option with the same shape as
  # firewall/meson.build. enabled (default) requires libsystemd; auto uses it when found;
  # disabled never does. Without it the fwupd read compiles as unreachable and reports
  # `fwupd:not_built`.
  libsystemd_dep = dependency('libsystemd', required: get_option('systemd_guard'),
                              include_type: 'system')
  if libsystemd_dep.found()
    firmware_posture_deps += libsystemd_dep
    firmware_posture_cpp_args += '-DYUZU_HAVE_LIBSYSTEMD'
  else
    message('FIRMWARE_POSTURE: libsystemd not used (systemd_guard != enabled, and not found) -- '
          + 'the fwupd read compiles as unreachable and reports fwupd:not_built')
  endif
endif

# Assigned (not anonymous) so tests/meson.build's link_depends can name this build output.
firmware_posture_plugin_lib = shared_library(
  'firmware_posture',
  files(
    'src/firmware_posture_plugin.cpp',
    'src/firmware_posture_linux.cpp',
    'src/firmware_posture_macos.cpp',
    'src/firmware_posture_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # constraint_accumulator.hpp, wmi_bounded.hpp
  cpp_args: firmware_posture_cpp_args,
  dependencies: firmware_posture_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
