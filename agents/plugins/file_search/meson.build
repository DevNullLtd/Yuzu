# file_search -- on-demand, resumable search of the local disks by leaf name (Linux, macOS and Windows legs).
# Multi-TU shape follows agents/plugins/pkg_inventory/meson.build: one portable plugin TU, one OS-neutral
# shell, the POSIX shell and the Windows shell and one extents shell per POSIX OS, each #if-gated internally
# for its own target (empty elsewhere), so every one is listed unconditionally.
#
# ONE RECORDED LATERAL SOURCE AND INCLUDE. The search drives the same no-follow filesystem leg the
# component_inventory plugin walks (walk_ordered and PosixFs, make_search_leg in component_legs.hpp), and
# there is no second walker. That code lives under component_inventory/src and is compiled into THIS plugin
# directly rather than hoisted to agents/shared, because another change owns the breadth-first walk it sits
# beside; the hoist is tracked in #8429 and replaces these two lines when it lands.
file_search_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]

if host_machine.system() == 'darwin'
  # CoreFoundation: CFStringNormalize and CFStringFold for the macOS name rule (NFC plus case folding).
  file_search_deps += dependency('appleframeworks', modules: ['CoreFoundation'], include_type: 'system')
elif host_machine.system() == 'windows'
  # advapi32: the ProfileList registry read of the profile roots. bcrypt (the cursor key's random draw) is
  # linked by #pragma comment(lib) in file_search_win.cpp, the content_dist precedent.
  file_search_deps += cxx.find_library('advapi32')
elif host_machine.system() == 'linux'
  # dladdr and dlopen pin the module at init: in libc on modern glibc, but explicitly linking libdl (when
  # present) keeps this working on older glibc without one (the same shape as tools/capmatrix-gen).
  file_search_deps += cxx.find_library('dl', required: false)
endif

# Assigned (not anonymous) so tests/meson.build's link_depends can name this build output.
file_search_plugin_lib = shared_library(
  'file_search',
  files(
    'src/file_search_plugin.cpp',
    'src/file_search_shell.cpp',
    'src/file_search_win.cpp',
    'src/file_search_posix.cpp',
    'src/file_search_extents_linux.cpp',
    'src/file_search_extents_macos.cpp',
    '../component_inventory/src/component_fs_posix.cpp',  # lateral: the POSIX search leg, see above
  ),
  name_prefix: '',
  include_directories: [
    include_directories('../../shared'),
    include_directories('src'),  # file_search_*.hpp, which include one another by angle brackets
    include_directories('../component_inventory/src'),  # lateral: component_walk.hpp, component_legs.hpp
  ],
  dependencies: file_search_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
# deploy_dlls (root meson.build) waits for every library in this list (#8926).
yuzu_plugin_libs += file_search_plugin_lib
