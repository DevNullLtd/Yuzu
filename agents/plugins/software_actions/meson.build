software_actions_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
if host_machine.system() == 'windows'
  software_actions_deps += cxx.find_library('advapi32')
endif

software_actions_plugin_lib = shared_library(
  'software_actions',
  files('src/software_actions_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681) -- from_wide for %LOCALAPPDATA%
  dependencies: software_actions_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
