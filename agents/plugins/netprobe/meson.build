netprobe_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

if host_machine.system() == 'windows'
  netprobe_deps += cxx.find_library('iphlpapi')
  netprobe_deps += cxx.find_library('ws2_32')
endif

netprobe_plugin_lib = shared_library(
  'netprobe',
  files('src/netprobe_plugin.cpp'),
  name_prefix: '',
  dependencies: netprobe_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
# deploy_dlls (root meson.build) waits for every library in this list (#8926).
yuzu_plugin_libs += netprobe_plugin_lib
