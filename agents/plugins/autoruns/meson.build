# autoruns — persistence-source enumeration ("what starts automatically")
# across Windows, Linux and macOS.
#
# Single portable plugin TU plus exactly ONE per-OS leg TU, chosen by
# host_machine.system() -- NOT the filesystem_posture/disk_actions shape of
# all-three-TUs-always-compiled. autoruns_legs.hpp supplies an inline
# foreign-OS stub for the two OSes this build does NOT compile a leg for
# (see that header's banner), so a single leg TU is sufficient for the build
# to link on every platform.
# libxml2_dep declared at root meson.build scope, unconditionally (every
# platform) -- autoruns_parsers.hpp's parse_task_xml parses Windows Task
# Scheduler XML via real libxml2 rather than hand-rolled scanning.
autoruns_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep, libxml2_dep]

autoruns_sources = files('src/autoruns_plugin.cpp')

if host_machine.system() == 'windows'
  # advapi32: Reg*W registry probes. ole32/oleaut32/wbemuuid: WMI
  # (root\subscription) COM plumbing. taskschd: ITaskService Task Scheduler
  # COM interface. shell32: SHGetKnownFolderPath (common Startup folder).
  autoruns_deps += [
    cxx.find_library('advapi32'),
    cxx.find_library('ole32'),
    cxx.find_library('oleaut32'),
    cxx.find_library('wbemuuid'),
    cxx.find_library('taskschd'),
    cxx.find_library('shell32'),
  ]
  autoruns_sources += files('src/autoruns_win.cpp')
elif host_machine.system() == 'linux'
  autoruns_sources += files('src/autoruns_linux.cpp')
elif host_machine.system() == 'darwin'
  # CFPropertyListCreateWithData over launchd plists.
  autoruns_deps += [
    dependency('appleframeworks', modules: ['CoreFoundation'], include_type: 'system'),
  ]
  autoruns_sources += files('src/autoruns_macos.cpp')
endif

# Assigned (not anonymous) so tests/meson.build's link_depends can name this
# build output, matching disk_actions_plugin_lib / filesystem_posture_plugin_lib.
autoruns_plugin_lib = shared_library(
  'autoruns',
  autoruns_sources,
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: autoruns_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
