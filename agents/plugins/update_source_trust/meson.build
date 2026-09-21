# update_source_trust -- package/update-source trust posture (read-only facts).
# Multi-TU shape follows agents/plugins/peripherals/meson.build: one portable
# plugin TU plus three per-OS leg TUs, each #ifdef-gated internally for its own
# target so all four are listed unconditionally. The leg TUs read config files
# and property lists in-process: no subprocess, so no argv-runner dependency.
update_source_trust_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]

if host_machine.system() == 'darwin'
  # CoreFoundation for CFPropertyListCreateWithData over the SoftwareUpdate
  # plists (update_source_trust_macos_parsers.hpp).
  update_source_trust_deps += dependency('appleframeworks', modules: ['CoreFoundation'],
                                         include_type: 'system')
endif

# Assigned (not anonymous) so tests/meson.build's link_depends can name this
# build output, matching peripherals_plugin_lib.
update_source_trust_plugin_lib = shared_library(
  'update_source_trust',
  files(
    'src/update_source_trust_plugin.cpp',
    'src/update_source_trust_linux.cpp',
    'src/update_source_trust_macos.cpp',
    'src/update_source_trust_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: update_source_trust_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
