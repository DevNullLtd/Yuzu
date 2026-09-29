# disk_actions — physical drive health + physical-to-logical volume mapping.
# Multi-TU shape follows agents/plugins/filesystem_posture/meson.build: one
# portable plugin TU plus three per-OS leg TUs, each #ifdef-gated internally
# for its own target so all four are listed unconditionally.
disk_actions_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]

if host_machine.system() == 'darwin'
  # IOKit for the block-device walk (identity, capability, IOMedia);
  # CoreFoundation for the property dictionaries those return.
  disk_actions_deps += [
    dependency('appleframeworks', modules: ['IOKit', 'CoreFoundation'], include_type: 'system'),
  ]
endif

# Assigned (not anonymous) so tests/meson.build's link_depends can name this
# build output, matching filesystem_posture_plugin_lib / disk_space.
disk_actions_plugin_lib = shared_library(
  'disk_actions',
  files(
    'src/disk_actions_plugin.cpp',
    'src/disk_actions_linux.cpp',
    'src/disk_actions_macos.cpp',
    'src/disk_actions_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: disk_actions_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
