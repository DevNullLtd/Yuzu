fs_extra_deps = []
if host_machine.system() == 'windows'
  version_lib = cxx.find_library('version')
  fs_extra_deps = [version_lib]
endif

shared_library(
  'filesystem',
  files('src/filesystem_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681, _WIN32-gated)
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep] + fs_extra_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
