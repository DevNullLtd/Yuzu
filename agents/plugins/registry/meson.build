# nlohmann_dep: registry_plan.hpp parses the apply plan (the asset_tags plugin's precedent).
registry_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, nlohmann_dep, spdlog_dep]
if host_machine.system() == 'windows'
  # win_profiles.hpp / win_reg_handle.hpp: Reg*W + RegLoadKeyW/RegUnLoadKeyW,
  # AdjustTokenPrivileges (PR1.7).
  registry_deps += [cxx.find_library('advapi32')]
endif

# Assigned so tests/meson.build link_depends can name it, matching shares_plugin_lib.
registry_plugin_lib = shared_library(
  'registry',
  files(
    'src/registry_plugin.cpp',
    'src/registry_win.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681), win_profiles.hpp/win_reg_handle.hpp/user_profile_model.hpp (PR1.7)
  dependencies: registry_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
