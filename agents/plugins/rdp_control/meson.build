rdp_control_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
if host_machine.system() == 'windows'
  # advapi32: registry + service control manager; ole32/oleaut32: INetFwPolicy2 COM
  rdp_control_deps += [cxx.find_library('advapi32'), cxx.find_library('ole32'), cxx.find_library('oleaut32')]
endif

shared_library(
  'rdp_control',
  files('src/rdp_control_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_com.hpp
  dependencies: rdp_control_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
