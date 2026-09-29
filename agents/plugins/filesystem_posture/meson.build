# filesystem_posture — mounted-filesystem / quota-subsystem / snapshot
# posture plugin. Modelled on agents/plugins/license_scan/meson.build for
# its multi-TU shape only -- license_scan's own dep list omits spdlog_dep
# (its TUs don't call it); this plugin's legs.hpp uses spdlog::warn, so
# spdlog_dep is included here.
filesystem_posture_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]

if host_machine.system() == 'windows'
  # vssapi: IVssBackupComponents / CreateVssBackupComponents /
  # VssFreeSnapshotProperties for the snapshots leg. ole32+oleaut32 were
  # already required by the IDiskQuotaControl quota path; VSS is COM too and
  # needs no additional runtime, only this import library.
  filesystem_posture_deps += [
    cxx.find_library('ole32'),
    cxx.find_library('oleaut32'),
    cxx.find_library('vssapi'),
  ]
endif

# Assigned (not anonymous) so tests/meson.build's link_depends can reference
# this build output by name -- same shape as network_config_plugin_lib /
# license_scan_plugin_lib. All four TUs are listed unconditionally; each is
# #ifdef-gated internally for its own target OS, exactly as license_scan
# does for licensing_win.cpp / licensing_linux.cpp / licensing_macos.cpp.
filesystem_posture_plugin_lib = shared_library(
  'filesystem_posture',
  files(
    'src/filesystem_posture_plugin.cpp',
    'src/filesystem_posture_linux.cpp',
    'src/filesystem_posture_macos.cpp',
    'src/filesystem_posture_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: filesystem_posture_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
