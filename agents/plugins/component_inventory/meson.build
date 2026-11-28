# component_inventory -- installed software components found in application trees (Java archives
# and the libraries nested in them, native shared libraries: ELF, Mach-O and PE, Python distributions and
# Node packages; nlohmann reads package.json). Read-only, zero
# subprocess. Multi-TU shape follows
# agents/plugins/runtimes/meson.build: one portable plugin TU plus the two filesystem legs, the POSIX
# one and the Windows one, each #if-gated internally for its own target so both are listed
# unconditionally.
#
# zlib: raw inflate of the two small entries read for a version. The server build defines its own
# zlib_dep (server/core/meson.build) and is configured AFTER the agent plugins, so this plugin
# finds zlib itself, the same way. tests/meson.build reuses this variable for the agent test target.
component_inventory_zlib_dep = dependency('ZLIB', method: 'cmake', modules: ['ZLIB::ZLIB'],
  required: false, include_type: 'system')
if not component_inventory_zlib_dep.found()
  component_inventory_zlib_dep = dependency('zlib', required: true, include_type: 'system')
endif

component_inventory_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep, nlohmann_dep, component_inventory_zlib_dep]
if host_machine.system() == 'windows'
  # shell32: SHGetKnownFolderPath (the Program Files roots); ole32: CoTaskMemFree for its result.
  component_inventory_deps += [cxx.find_library('shell32'), cxx.find_library('ole32')]
endif

# Assigned (not anonymous) so tests/meson.build's link_depends can name this build output,
# matching runtimes_plugin_lib.
component_inventory_plugin_lib = shared_library(
  'component_inventory',
  files(
    'src/component_inventory_plugin.cpp',
    'src/component_fs_posix.cpp',
    'src/component_fs_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: component_inventory_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
# deploy_dlls (root meson.build) waits for every library in this list (#8926).
yuzu_plugin_libs += component_inventory_plugin_lib
