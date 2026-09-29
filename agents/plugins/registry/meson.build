registry_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]
if host_machine.system() == 'windows'
  # win_profiles.hpp / win_reg_handle.hpp: Reg*W + RegLoadKeyW/RegUnLoadKeyW,
  # AdjustTokenPrivileges (PR1.7).
  registry_deps += [cxx.find_library('advapi32')]
endif

shared_library(
  'registry',
  files('src/registry_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681), win_profiles.hpp/win_reg_handle.hpp/user_profile_model.hpp (PR1.7)
  dependencies: registry_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
