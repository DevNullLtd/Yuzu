wmi_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
if host_machine.system() == 'windows'
  wmi_deps += [cxx.find_library('wbemuuid'), cxx.find_library('ole32'), cxx.find_library('oleaut32')]
endif

wmi_plugin_lib = shared_library(
  'wmi',
  files('src/wmi_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681) + wmi_bounded.hpp / win_com.hpp
  dependencies: wmi_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
# deploy_dlls (root meson.build) waits for every library in this list (#8926).
yuzu_plugin_libs += wmi_plugin_lib
