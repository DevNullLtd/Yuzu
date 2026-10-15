# peripherals — USB, PCI and Thunderbolt/USB4 bus inventory (read-only).
# Multi-TU shape follows agents/plugins/disk_actions/meson.build: one
# portable plugin TU plus three per-OS leg TUs, each #ifdef-gated internally
# for its own target so all four are listed unconditionally.
peripherals_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]
peripherals_objcpp_args = []

if host_machine.system() == 'windows'
  peripherals_deps += [
    cxx.find_library('setupapi'),
  ]
elif host_machine.system() == 'darwin'
  # IOKit for the device-tree walks (usb/pci/thunderbolt matching);
  # CoreFoundation for the property dictionaries those return.
  peripherals_deps += dependency('appleframeworks', modules: ['IOKit', 'CoreFoundation'],
                                 include_type: 'system')
endif

# Assigned (not anonymous) so tests/meson.build's link_depends can name this
# build output, matching disk_actions_plugin_lib / filesystem_posture_plugin_lib.
peripherals_plugin_lib = shared_library(
  'peripherals',
  files(
    'src/peripherals_plugin.cpp',
    'src/peripherals_linux.cpp',
    'src/peripherals_macos.cpp',
    'src/peripherals_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: peripherals_deps,
  objcpp_args: peripherals_objcpp_args,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
